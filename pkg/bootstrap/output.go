package bootstrap

import (
	"fmt"
	"log/slog"
	"strings"
)

// PrintBootstrapResult displays the bootstrap results in a clean, formatted way
func PrintBootstrapResult(result *AdminBootstrapResult) {
	if result == nil || !result.UserCreated {
		return
	}

	// Print section header
	printSectionHeader("ADMIN BOOTSTRAP COMPLETED")

	// Print roles information
	printRolesSection(result.Roles, result.PrimaryRole)

	// Print user information
	printUserSection(result)

	// Print security warnings
	printSecurityWarnings(result.PasswordFromEnv)

	// Print section footer
	printSectionFooter()
}

// printSectionHeader prints a formatted section header
func printSectionHeader(title string) {
	border := strings.Repeat("=", 80)
	fmt.Printf("\n%s\n", border)
	fmt.Printf("🚀 %s\n", title)
	fmt.Printf("%s\n", border)
}

// printSectionFooter prints a formatted section footer
func printSectionFooter() {
	border := strings.Repeat("=", 80)
	fmt.Printf("%s\n\n", border)
}

// printRolesSection prints information about bootstrapped roles
func printRolesSection(roles []AdminRoleInfo, primaryRole AdminRoleInfo) {
	fmt.Println("\n📋 Admin Roles:")
	fmt.Println(strings.Repeat("-", 80))

	for i, role := range roles {
		status := "✓ Already existed"
		if role.Created {
			status = "✨ Created"
		}

		isPrimary := ""
		if role.ID == primaryRole.ID {
			isPrimary = " (PRIMARY - assigned to admin user)"
		}

		fmt.Printf("  %d. %s%s\n", i+1, role.Name, isPrimary)
		fmt.Printf("     ID: %s\n", role.ID)
		fmt.Printf("     Status: %s\n", status)

		if i < len(roles)-1 {
			fmt.Println()
		}
	}
}

// printUserSection prints information about the created admin user
func printUserSection(result *AdminBootstrapResult) {
	fmt.Println("\n👤 Admin User:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("  Username:  %s\n", result.Username)
	fmt.Printf("  Email:     %s\n", result.Email)
	fmt.Printf("  User ID:   %s\n", result.UserID)
	fmt.Printf("  Login ID:  %s\n", result.LoginID)
	fmt.Printf("  Role:      %s\n", result.PrimaryRole.Name)

	// Only display password if it was auto-generated (not from environment)
	if !result.PasswordFromEnv {
		fmt.Printf("  Password:  %s\n", result.Password)
	} else {
		fmt.Printf("  Password:  (configured via ADMIN_PASSWORD environment variable)\n")
	}
}

// printSecurityWarnings prints important security warnings
func printSecurityWarnings(passwordFromEnv bool) {
	fmt.Println("\n⚠️  SECURITY REMINDERS:")
	fmt.Println(strings.Repeat("-", 80))

	if passwordFromEnv {
		fmt.Println("  • Admin password was set via environment variable")
		fmt.Println("  • Ensure ADMIN_PASSWORD is removed from .env after first login")
		fmt.Println("  • Change the password after logging in for the first time")
	} else {
		fmt.Println("  • THIS PASSWORD WILL NOT BE DISPLAYED AGAIN - SAVE IT NOW!")
		fmt.Println("  • Store credentials in a secure password manager")
		fmt.Println("  • Change the password after logging in for the first time")
	}

	fmt.Println("  • Remove or secure environment variables containing credentials")
	fmt.Println("  • Enable 2FA for the admin account after first login")
}

// LogBootstrapSummary logs a concise summary using slog (for structured logging)
func LogBootstrapSummary(result *AdminBootstrapResult) {
	if result == nil || !result.UserCreated {
		return
	}

	// Log without sensitive information (password)
	slog.Info("Admin bootstrap summary",
		"roles_total", len(result.Roles),
		"roles_created", countCreatedRoles(result.Roles),
		"primary_role", result.PrimaryRole.Name,
		"admin_username", result.Username,
		"admin_email", result.Email,
		"user_id", result.UserID,
		"login_id", result.LoginID,
		"password_from_env", result.PasswordFromEnv,
	)
}

// countCreatedRoles counts how many roles were newly created
func countCreatedRoles(roles []AdminRoleInfo) int {
	count := 0
	for _, role := range roles {
		if role.Created {
			count++
		}
	}
	return count
}
