package webcommrsa

import (
	"math"
	"math/rand"
	"strconv"
	"time"
)

type WebcommRsa struct {
}

func encrypt(plainText []byte, pubkey int, modu int) string {
	cipherText := ""

	if plen := len(plainText); plen >= 0 {
		for x := 0; x < plen; x++ {
			code := int(plainText[x])
			result := 0
			mod := 0
			half := pubkey >> 1

			if pubkey%2 == 0 {
				result = 1
				for i := 0; i < half; i++ {
					mod = (code * code) % modu
					result = (mod * result) % modu
				}
			} else {
				result = code % modu

				for i := half; i >= 1; i-- {
					mod = (code * code) % modu
					result = (mod * result) % modu
				}
			}

			strAdd0 := strconv.FormatInt(int64(result), 16)
			add0In := len(strAdd0)

			if add0In <= 4 {
				add0In = 4 - add0In

				for i := 0; i < add0In; i++ {
					strAdd0 = "0" + strAdd0
				}
			}
			cipherText += strAdd0
		}
	}

	return cipherText
}

func decrypt(cipherText string, prikey int, modu int) []byte {
	bsize := len(cipherText)
	byteBuffer := make([]byte, bsize)
	j := 0

	for x := 0; x < len(cipherText); x += 4 {
		if c64, err := strconv.ParseInt(cipherText[x:x+4], 16, 32); err == nil {
			result := 0
			half := prikey >> 1
			code := int(c64)

			if prikey%2 == 0 {
				result = 1
				for i := 0; i < half; i++ {
					m := (code * code) % modu
					result = (m * result) % modu
				}
			} else {
				result = code % modu
				for i := half; i >= 1; i-- {
					m := (code * code) % modu
					result = (m * result) % modu
				}
			}
			byteBuffer[j] = byte(result)
			j++
		}
	}
	plainText := byteBuffer[:j]

	return plainText
}

func isPrime(n int) bool {
	if n%2 == 0 || n == 1 {
		return false
	} else {
		max := int(math.Floor(math.Sqrt(float64(n))))

		for i := 3; i <= max; i += 2 {
			if n%i == 0 {
				return false
			}
		}
		return true
	}
}

func pickPrime(against int) int {
	p := against

	for (p == against) || !isPrime(p) {
		p = 10 + int(math.Floor(rand.Float64()*100.0))
	}
	return p
}

func gcd(m, n int) int {
	var x int

	for x = m % n; x != 0; x = m % n {
		m = n
		n = x
	}
	return n
}

func euler(phi, e int) int {
	pp := []int{1, 0, 0}
	qq := []int{0, 2, 0}
	rr := []int{e, phi, 0}

	for rr[0] != 0 {
		rr[1], rr[2] = rr[0], rr[1]
		pp[1], pp[2] = pp[0], pp[1]
		qq[1], qq[2] = qq[0], qq[1]

		rr[0] = rr[2] % rr[1]
		ratio := int(math.Floor(float64(rr[2])/float64(rr[1]) + 0.5))
		pp[0] = ratio*pp[1] + pp[2]
		qq[0] = ratio*qq[1] + qq[2]
	}

	if result := e*pp[1] - phi*qq[1]; result > 0 {
		return pp[1]
	} else if pp[1] > 0 {
		return phi + pp[1]
	} else {
		return phi - pp[1]
	}
}

func reCrypt(message int, pkey int, modu int) int {
	result := 1
	half := pkey >> 1

	if pkey%2 == 0 {
		for i := half; i > 0; i-- {
			m := (message * message) % modu
			result = (m * result) % modu
		}
	} else {
		result = message % modu

		for i := half; i >= 1; i-- {
			m := (message * message) % modu
			result = (m * result) % modu
		}
	}

	return result
}

func testCrypt(testVal int, rsa []int) bool {
	lstrCrypted := reCrypt(testVal, rsa[0], rsa[2])
	compare := reCrypt(lstrCrypted, rsa[1], rsa[2])

	return compare == testVal
}

func GenerateKey(message string) ([]int, string) {
	rand.Seed(time.Now().UTC().UnixNano())

	finalFlag := false
	rsaKey := []int{0, 0, 0}
	cipherText := ""

	plainText := []byte(message)

	for !finalFlag {
		for {
			// 1. select 2 prime numbers: p and q
			p := pickPrime(2)
			q := pickPrime(p)

			// 2. compute n = p * q
			//    compute phi = (p - 1) * (q - 1)
			n := p * q
			phi := (p - 1) * (q - 1)
			e := n

			// 3. choose e such that (1 < e < phi) and (e and n are coprime)

			for gcd(e, n) != 1 {
				e = int(math.Floor(rand.Float64()*float64(phi-2)) + 2)
				// fmt.Println("n=", n, ", e=", e, ",gcd=", gcd(e, n))
			}

			d := euler(phi, e)

			rsaKey[0], rsaKey[1], rsaKey[2] = e, d, n

			if !(d == 0 || d == 1 || e == d) {
				break
			}
		}

		if finalFlag = testCrypt(255, rsaKey); finalFlag {
			cipherText = encrypt(plainText, rsaKey[0], rsaKey[2])
			result := decrypt(cipherText, rsaKey[1], rsaKey[2])

			if len(result) != len(plainText) {
				finalFlag = false
			} else {
				for i := 0; i < len(result); i++ {
					if result[i] != plainText[i] {
						finalFlag = false
						break
					}
				}
			}
		}

	}

	return rsaKey, cipherText
}
