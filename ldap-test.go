package main

import (
	"fmt"
)

func main() {
	fmt.Println()
	fmt.Println("First level of the AD/OpenLDAP tree")
	fmt.Println("------------------------------------------------------------------")
	levelZero := adGetTree()
	levelOne := *levelZero.Children
	for index := 0; index < len(levelOne); index++ {
		fmt.Println(levelOne[index].Name)
	}
	fmt.Println()

	fmt.Println("Users which OU is OU=level2,OU=level1,DC=example,DC=local")
	fmt.Println("------------------------------------------------------------------")
	users := adGetUsers("level2,OU=level1")
	for index := 0; index < len(users); index++ {
		fmt.Println(users[index].SAMAccountName)
	}
	fmt.Println()

	fmt.Println("Users with name/username starting with 'nicol'")
	fmt.Println("------------------------------------------------------------------")
	users = adGetUser("nicol")
	for index := 0; index < len(users); index++ {
		fmt.Println(users[index].SAMAccountName)
	}
	fmt.Println()

}
