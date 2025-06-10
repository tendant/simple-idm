package signup

// InvitationCodes contains all the invitation codes and their corresponding roles
// These are used in the registration process to assign roles to new users
type InvitationCode struct {
	Code string
	Role string
}

// All invitation codes mapped to their roles
var InvitationCodes = map[string]string{
	"ACC-X7F9D2": "accounting",
	"ADM-K3P8Q5": "admin",
	"FRD-T6M2Z7": "fraud",
	"RDO-J5H3V9": "readonlyuser",
	"RCP-N4B7L2": "receipt",
	"RSK-C8W6P4": "risk",
	"STL-G1Y5R3": "settlement",
	"STM-Q9E2S6": "statement",
	"SPR-Z3X7V1": "superadmin",
	"SUP-L6D4F8": "support",
	"UND-B2H5M9": "underwriting",
	"DEM-R7T9F3": "demo",
}

// GetRoleForInvitationCode returns the role for a given invitation code
// If the code is not recognized, it returns an empty string
func GetRoleForInvitationCode(code string) (string, bool) {
	role, exists := InvitationCodes[code]
	return role, exists
}
