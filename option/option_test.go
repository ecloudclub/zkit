package option

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApply(t *testing.T) {
	u := &User{}
	Apply[User](u, WithName("Tom"), WithAge(18))
	assert.Equal(t, u, &User{name: "Tom", age: 18})
}

func ExampleApply() {
	u := &User{}
	Apply[User](u, WithName("Tom"), WithAge(18))
	fmt.Println(u)
	// Output:
	// &{Tom 18}
}

func WithName(name string) Option[User] {
	return func(u *User) {
		u.name = name
	}
}

func WithAge(age int) Option[User] {
	return func(u *User) {
		u.age = age
	}
}

type User struct {
	name string
	age  int
}
