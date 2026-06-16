package main

func main() {
	// Calling the function from update.go directly
	CheckAndPerformUpdate()

	// Proceeding to the main Cobra CLI logic
	Execute()
}