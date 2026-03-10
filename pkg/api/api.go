// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

import (
	"encoding/json"
	"time"
)

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionFetchData  = "fetchData"
	ActionUpdateData = "updateData"
	ActionLogout     = "logout"
	ActionLookup     = "lookup"
)

/*
	type Request struct {
		Action   string `json:"action"`
		Username string `json:"username"`
		Password string `json:"password,omitempty"`
		Token    string `json:"token,omitempty"`
		Data     string `json:"data,omitempty"`
	}
*/
type Request struct {
	Action string          `json:"action"`
	Token  string          `json:"token,omitempty"`
	ReqID  string          `json:"reqID,omitempty"`
	Body   json.RawMessage `json:"body,omitempty"`
	Data   string          `json:"data,omitempty"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
	Data    string `json:"data,omitempty"`
}

type file struct {
	Name        string    `json:"name"`
	Content     string    `json:"content"`
	Modified    time.Time `json:"modified"`
	Created     time.Time `json:"created"`
	Permissions string    `json:"permissions"` //Estilo linux
	Size        int64     `json:"size"`        //En bytes
	Path        string    `json:"path"`        // /home/user/docs no  \
	IsDirectory bool      `json:"isDirectory"` //Separa los ficheros como csv
}
