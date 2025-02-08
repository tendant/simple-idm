package utils

import "database/sql"

// StringPtr returns a pointer to the string value passed in
func StringPtr(s string) *string {
	return &s
}

func ToNullString(str string) sql.NullString {
	if str == "" {
		return sql.NullString{
			String: str,
			Valid:  false,
		}
	}
	return sql.NullString{
		String: str,
		Valid:  true,
	}
}

func GetValidStrings(nullStrings []sql.NullString) []string {
	var validStrings []string

	for _, ns := range nullStrings {
		if ns.Valid {
			validStrings = append(validStrings, ns.String)
		}
	}

	return validStrings
}
