package utils

import "database/sql"

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
