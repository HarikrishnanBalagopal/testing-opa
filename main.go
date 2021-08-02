package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/cast"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type IDType int

type Asset struct {
	ID   IDType `json:"id"`
	Name string `json:"name"`
	Path string `json:"-"`
}

type Artifact struct {
	ID   IDType `json:"id"`
	Name string `json:"name"`
	Path string `json:"-"`
}

type Project struct {
	ID        IDType              `json:"id"`
	Name      string              `json:"name"`
	Assets    map[IDType]Asset    `json:"assets,omitempty"`
	Artifacts map[IDType]Artifact `json:"artifacts,omitempty"`
}

type WorkSpace struct {
	ID       IDType             `json:"id"`
	Name     string             `json:"name"`
	Projects map[IDType]Project `json:"projects,omitempty"`
}

var WORKSPACES = map[IDType]WorkSpace{
	42: {42, "w42", map[IDType]Project{1337: {1337, "p1337", map[IDType]Asset{111: {111, "as111", "cool"}}, nil}}},
}

func GetWorkspace(wid IDType) (WorkSpace, error) {
	w, ok := WORKSPACES[wid]
	if !ok {
		return w, fmt.Errorf("no workspace found with id: %v", wid)
	}
	return w, nil
}

func GetProjectInWorkspace(wid, pid IDType) (Project, error) {
	w, ok := WORKSPACES[wid]
	if !ok {
		return Project{}, fmt.Errorf("no workspace found with id: %v", wid)
	}
	p, ok := w.Projects[pid]
	if !ok {
		return p, fmt.Errorf("no project found with id: %v in the workspace with id: %v", pid, wid)
	}
	return p, nil
}

func GetWorkspaces() map[IDType]WorkSpace {
	return WORKSPACES
}

func handleGetProject(resp http.ResponseWriter, req *http.Request) {
	routeVars := mux.Vars(req)
	resp.Header().Set("Content-Type", "application/json")
	wid := IDType(cast.ToInt(routeVars["wid"]))
	pid := IDType(cast.ToInt(routeVars["pid"]))
	body, err := GetProjectInWorkspace(wid, pid)
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		errBytes, e := json.Marshal(map[string]string{"error": err.Error()})
		must(e)
		resp.Write(errBytes)
		return
	}
	bodyBytes, err := json.Marshal(body)
	must(err)
	resp.Write(bodyBytes)
}

func handleGetWorkspace(resp http.ResponseWriter, req *http.Request) {
	routeVars := mux.Vars(req)
	resp.Header().Set("Content-Type", "application/json")
	wid := IDType(cast.ToInt(routeVars["wid"]))
	body, err := GetWorkspace(wid)
	if err != nil {
		resp.WriteHeader(http.StatusNotFound)
		errBytes, e := json.Marshal(map[string]string{"error": err.Error()})
		must(e)
		resp.Write(errBytes)
		return
	}
	bodyBytes, err := json.Marshal(body)
	must(err)
	resp.Write(bodyBytes)
}

func handleGetWorkspaces(resp http.ResponseWriter, req *http.Request) {
	resp.Header().Set("Content-Type", "application/json")
	body := GetWorkspaces()
	bodyBytes, err := json.Marshal(body)
	must(err)
	resp.Write(bodyBytes)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		fmt.Println(req.Method, req.RequestURI)
		next.ServeHTTP(resp, req)
	})
}

func getUserFromAccessToken(accessToken string) (string, error) {
	if accessToken == "" {
		return "", fmt.Errorf("the access token is empty")
	}
	// TODO: verify the JWT access token and get the user from the JWT
	return accessToken, nil
}

func setupAPIServer(port int, isAuth IsAuthorized) {
	authorizationMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
			authHeader := req.Header["Authorization"]
			if len(authHeader) != 1 {
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			parts := strings.Split(authHeader[0], " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			accessToken := strings.TrimSpace(parts[1])
			user, err := getUserFromAccessToken(accessToken)
			if err != nil {
				resp.WriteHeader(http.StatusBadRequest)
				errBytes, e := json.Marshal(map[string]string{"error": err.Error()})
				must(e)
				resp.Write(errBytes)
				return
			}
			subject := user
			object := strings.Split(req.URL.Path, "/")[3:] // skip ["", "api", "v1"]
			action := req.Method
			ok, err := isAuth(subject, object, action)
			if err != nil {
				resp.WriteHeader(http.StatusBadRequest)
				return
			}
			if !ok {
				resp.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(resp, req)
		})
	}

	router := mux.NewRouter()
	router.Use(loggingMiddleware)

	authorizedRouter := router.PathPrefix("/api/v1").Subrouter()
	authorizedRouter.Use(authorizationMiddleware)
	authorizedRouter.Methods("GET").Path("/workspaces/{wid:[0-9]+}/projects/{pid:[0-9]+}").HandlerFunc(handleGetProject)
	authorizedRouter.Methods("GET").Path("/workspaces/{wid:[0-9]+}").HandlerFunc(handleGetWorkspace)
	authorizedRouter.Methods("GET").Path("/workspaces").HandlerFunc(handleGetWorkspaces)

	router.Methods("GET").Handler(http.FileServer(http.Dir("public")))

	must(http.ListenAndServe(fmt.Sprintf(":%d", port), router))
}

func main() {
	fmt.Println("start")
	isAuth, err := setupAuth()
	must(err)
	setupAPIServer(8080, isAuth)
	fmt.Println("done")
}

// Authorization

type IsAuthorized = func(subject string, object []string, action string) (bool, error)

func setupAuth() (IsAuthorized, error) {
	MODULE := `
package example.authz

default allow = false

allow {
	input.subject.id = "john"
	input.object = ["workspaces", "42"]
	input.action = "GET"
}

allow {
	is_admin
}

is_admin {
	input.subject.roles[_] = "admin"
}
`
	query, err := rego.New(rego.Query("x = data.example.authz.allow"), rego.Module("example.rego", MODULE)).PrepareForEval(context.TODO())
	must(err)

	isAuth := func(subject string, object []string, action string) (bool, error) {
		fmt.Printf("checking authorization for %s to perform %s on %v\n", subject, action, object)
		input := map[string]interface{}{
			"subject": map[string]interface{}{
				"id":    subject,
				"roles": GetRolesOfUser(subject),
			},
			"object": object,
			"action": action,
		}
		res, err := query.Eval(context.TODO(), rego.EvalInput(input))
		if err != nil {
			return false, err
		}
		if len(res) == 0 {
			return false, nil
		}
		allow, ok := res[0].Bindings["x"].(bool)
		if !ok {
			return false, nil
		}
		return allow, nil
	}
	return isAuth, nil
}

func GetRolesOfUser(user string) []string {
	ROLES := map[string][]string{"john": {"sales", "marketing"}, "sam": {"manager", "admin"}}
	return ROLES[user]
}
