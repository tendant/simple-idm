package main

import (
	"github.com/tendant/chi-demo/app"
	"github.com/tendant/simple-idm/demoService"
)

func main() {
	myApp := app.Default()

	handler := demoService.Handle{}
	demoService.Routes(myApp.R, handler)

	myApp.Run()
}
