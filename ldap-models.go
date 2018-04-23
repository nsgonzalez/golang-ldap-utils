package main

// ADOrganizationalUnitR is a map entry that contains the OU's
// name and it's parent name.
type ADOrganizationalUnitR struct {
	name   string
	parent string
}

// ADOrganizationalUnit is a tree entry that contains the OU's
// name and a set of pointers to its children.
type ADOrganizationalUnit struct {
	Name     string                  `json:"value"`
	Children *[]ADOrganizationalUnit `json:"children"`
}

// ADUser is a model containing most of the AD/LDAP user's object
// attributes.
type ADUser struct {
	DN                         string
	CN                         string
	SAMAccountName             string
	Description                string
	DisplayName                string
	GivenName                  string
	HomeDrive                  string
	Name                       string
	PhysicalDeliveryOfficeName string
	PostOfficeBox              string
	ProfilePath                string
	Title                      string
	UserPrincipalName          string
	Mail                       string
	Company                    string
	Department                 string
	Homephone                  string
	L                          string
	City                       string
	Manager                    string
	Mobile                     string
	PwdLastSet                 string
	PwdExpires                 string
	PostalCode                 string
	ST                         string
	StreetAddress              string
	TelephoneNumber            string
	Groups                     []string
	ScriptPath                 string
}

// ADGroup is a model containing the group's name and its full DN.
type ADGroup struct {
	DN             string
	CN             string
	SAMAccountName string
}
