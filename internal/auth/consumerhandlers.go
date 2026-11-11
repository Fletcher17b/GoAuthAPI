package auth

import (
	"AuthAPI/main/internal/models"
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"
)

var MasterTenantID = "00000000-0000-0000-0000-000000000002"

type ConsumerSignupPacket struct {
	Name  string // companyname
	URL   string
	Email string
}

func ConsumerSignupHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		var req models.Tenant

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		if err := decoder.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: err.Error(),
			})
		}

		if err := validateEmail(req.Email); err != nil {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: err.Error(),
			})
			return
		}

		tenant, success := TenantFromContext(r.Context())
		if !success {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "no tenant header",
			})
			return
		}

		parsedMTID, err := uuid.Parse(MasterTenantID)
		if err != nil {
			log.Fatalf("failed to parse UUID: %v", err) // nts: TODO: change to logger
		}

		// nts: TODO: this is gonna be hardcoded but will be changed in the future
		if tenant.ID != parsedMTID {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: "Invalid Tenant",
			})
			return
		}

	}
}
