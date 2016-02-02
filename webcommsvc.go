package webcommrsa

import (
	//"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

type RequestData struct {
	PlainText string `form:"plaintext" json:"plaintext" binding:"required"`
}

type ResponseData struct {
	PublicKey  int    `form:"publickey" json:"publickey" binding:"required"`
	PrivateKey int    `form:"privatekey" json:"privatekey" binding:"required"`
	Modulus    int    `form:"modulus" json:"modulus" binding:"required"`
	CipherText string `form:"ciphertext" json:"ciphertext" binding:"required"`
	Status     string `form:"status" json:"status"`
}

type WebcommService struct {
	G_engine *gin.Engine `@Autowired:"*"`
}

func (svc *WebcommService) PostSummerConstruct() {
	svc.G_engine.GET("/webcomm", func(c *gin.Context) {
		var req RequestData

		if c.BindJSON(&req) == nil {
			key, cipher := GenerateKey(req.PlainText)
			response := &ResponseData{
				PublicKey:  key[0],
				PrivateKey: key[1],
				Modulus:    key[2],
				CipherText: cipher,
				Status:     "success"}
			c.JSON(http.StatusOK, response)
		} else {
			c.JSON(http.StatusOK, gin.H{"status": "failed"})
		}
	})
}
