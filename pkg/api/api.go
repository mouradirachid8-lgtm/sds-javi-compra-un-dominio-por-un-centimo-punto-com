// El paquete api contiene las estructuras necesarias
// para la comunicación entre servidor y cliente.
package api

import "encoding/json"

const (
	ActionRegister   = "register"
	ActionLogin      = "login"
	ActionFetchData  = "fetchData"
	ActionUpdateData = "updateData"
	ActionLogout     = "logout"
)

type Request struct {
	Action   string `json:"action"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	Data     string `json:"data,omitempty"`
}

type NewRequest struct {
	Action string          `json:"action"`
	Token  string          `json:"token,omitempty"`
	ReqID  string          `json:"reqID,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
	Data    string `json:"data,omitempty"`
}
