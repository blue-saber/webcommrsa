# webcommrsa
 Do not clone this repository!!!   It is just a tiny useless program, for testing purpose.

```go
package main

import (
	"fmt"
	"github.com/blue-saber/webcommrsa"
)

func main() {
	key, cipher := webcommrsa.GenerateKey("The quick brown fox jumps over the lazy dog.")
	fmt.Println(key)
	fmt.Println(cipher)
}
```
