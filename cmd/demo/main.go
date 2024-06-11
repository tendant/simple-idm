package main

import "github.com/tendant/chi-demo/app"

func main() {
	myApp := app.Default()

	myApp.Run()
}
