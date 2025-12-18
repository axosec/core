//go:build js && wasm

package main

import (
	"crypto/ed25519"
	"fmt"
	"syscall/js"

	"github.com/axosec/core/crypto/box"
	"github.com/axosec/core/crypto/hash"
	"github.com/axosec/core/crypto/sign"
	"github.com/axosec/core/crypto/vault"
	"github.com/axosec/core/utils"
)

// bytesToJS converts Go []byte to JavaScript Uint8Array
func bytesToJS(data []byte) js.Value {
	dst := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(dst, data)
	return dst
}

// jsToBytes converts JavaScript Uint8Array to Go []byte
func jsToBytes(value js.Value) []byte {
	length := value.Get("length").Int()
	data := make([]byte, length)
	js.CopyBytesToGo(data, value)
	return data
}

// returnError returns a standard JS object: { error: "message" }
func returnError(err error) interface{} {
	return map[string]interface{}{
		"error": err.Error(),
	}
}

// returnCipherResult returns a standard JS object: { "data": ..., "nonce": ... }
func returnCipherResult(data, nonce []byte) interface{} {
	return map[string]interface{}{
		"data":  bytesToJS(data),
		"nonce": bytesToJS(nonce),
	}
}

// Hash Bindings

func HashCreate(this js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return returnError(fmt.Errorf("expected 1 argument: password"))
	}
	password := args[0].String()

	hashStr, err := hash.Create(password)
	if err != nil {
		return returnError(err)
	}
	return hashStr
}

func HashVerify(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return returnError(fmt.Errorf("expected 2 arguments: password, hash"))
	}
	password := args[0].String()
	hashStr := args[1].String()

	valid, err := hash.Verify(password, hashStr)
	if err != nil {
		return returnError(err)
	}
	return valid
}

func DeriveKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return returnError(fmt.Errorf("expected 2 arguments: password, salt"))
	}
	password := args[0].String()
	salt := jsToBytes(args[1])

	key, err := hash.DeriveKey(password, salt)
	if err != nil {
		return returnError(err)
	}
	return bytesToJS(key)
}

// Vault Bindings (Symmetric)

func VaultEncrypt(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return returnError(fmt.Errorf("expected 2 arguments: data, key"))
	}
	data := jsToBytes(args[0])
	key := jsToBytes(args[1])

	ciphertext, nonce, err := vault.Encrypt(data, key)
	if err != nil {
		return returnError(err)
	}
	return returnCipherResult(ciphertext, nonce)
}

func VaultDecrypt(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return returnError(fmt.Errorf("expected 3 arguments: data, nonce, key"))
	}
	data := jsToBytes(args[0])
	nonce := jsToBytes(args[1])
	key := jsToBytes(args[2])

	decrypted, err := vault.Decrypt(data, nonce, key)
	if err != nil {
		return returnError(err)
	}
	return bytesToJS(decrypted)
}

// Box Bindings (Asymmetric)

func BoxGenerateKey(this js.Value, args []js.Value) interface{} {
	kp, err := box.GenerateKeyPair()
	if err != nil {
		return returnError(err)
	}
	priv, pub := kp.Bytes()

	return map[string]interface{}{
		"private": bytesToJS(priv),
		"public":  bytesToJS(pub),
	}
}

func BoxSeal(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return returnError(fmt.Errorf("expected 2 arguments: data, peerPub"))
	}
	data := jsToBytes(args[0])
	peerPubBytes := jsToBytes(args[1])

	peerPub, err := box.LoadPublicKey(peerPubBytes)
	if err != nil {
		return returnError(err)
	}

	encBlob, nonce, err := box.Seal(data, peerPub)
	if err != nil {
		return returnError(err)
	}
	return returnCipherResult(encBlob, nonce)
}

func BoxUnseal(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return returnError(fmt.Errorf("expected 3 arguments: data, nonce, myPriv"))
	}
	data := jsToBytes(args[0])
	nonce := jsToBytes(args[1])
	myPrivBytes := jsToBytes(args[2])

	myPriv, err := box.LoadPrivateKey(myPrivBytes)
	if err != nil {
		return returnError(err)
	}

	plaintext, err := box.Unseal(data, nonce, myPriv.Private)
	if err != nil {
		return returnError(err)
	}
	return bytesToJS(plaintext)
}

func BoxWrapKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return returnError(fmt.Errorf("expected 2 arguments: keyToShare, peerPub"))
	}
	keyToShare := jsToBytes(args[0])
	peerPubBytes := jsToBytes(args[1])

	peerPub, err := box.LoadPublicKey(peerPubBytes)
	if err != nil {
		return returnError(err)
	}

	wrappedBlob, nonce, err := box.WrapKey(keyToShare, peerPub)
	if err != nil {
		return returnError(err)
	}
	return returnCipherResult(wrappedBlob, nonce)
}

func BoxUnwrapKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return returnError(fmt.Errorf("expected 3 arguments: wrappedBlob, nonce, myPriv"))
	}
	blob := jsToBytes(args[0])
	nonce := jsToBytes(args[1])
	myPrivBytes := jsToBytes(args[2])

	myPriv, err := box.LoadPrivateKey(myPrivBytes)
	if err != nil {
		return returnError(err)
	}

	key, err := box.UnwrapKey(blob, nonce, myPriv.Private)
	if err != nil {
		return returnError(err)
	}
	return bytesToJS(key)
}

func UtilGenerateSalt(this js.Value, args []js.Value) interface{} {
	length := 16
	if len(args) > 0 && args[0].Type() == js.TypeNumber {
		length = args[0].Int()
	}

	salt, err := utils.GenerateSalt(uint(length))
	if err != nil {
		return returnError(err)
	}
	return bytesToJS(salt)
}

// Sign Bindings (Asymmetric)

func SignGenerateKey(this js.Value, args []js.Value) interface{} {
	kp, err := sign.GenerateKeyPair()
	if err != nil {
		return returnError(err)
	}
	priv, pub := kp.Bytes()
	return map[string]interface{}{
		"private": bytesToJS(priv),
		"public":  bytesToJS(pub),
	}
}

func SignMessage(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return returnError(fmt.Errorf("expected 2 arguments: message, privateKey"))
	}
	message := jsToBytes(args[0])
	privKeyBytes := jsToBytes(args[1])

	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return returnError(fmt.Errorf("invalid private key size"))
	}

	signer := sign.NewSigner()
	signature := signer.Sign(message, privKeyBytes)

	return bytesToJS(signature)
}

func SignVerify(this js.Value, args []js.Value) interface{} {
	if len(args) != 3 {
		return returnError(fmt.Errorf("expected 3 arguments: message, signature, publicKey"))
	}
	message := jsToBytes(args[0])
	signature := jsToBytes(args[1])
	pubKeyBytes := jsToBytes(args[2])

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return returnError(fmt.Errorf("invalid public key size"))
	}

	signer := sign.NewSigner()
	valid := signer.Verify(message, signature, pubKeyBytes)

	return valid
}

func main() {
	c := make(chan struct{}, 0)
	fmt.Println("Axosec Core WASM Loaded")

	js.Global().Set("AxoHashCreate", js.FuncOf(HashCreate))
	js.Global().Set("AxoHashVerify", js.FuncOf(HashVerify))
	js.Global().Set("AxoHashDeriveKey", js.FuncOf(DeriveKey))

	js.Global().Set("AxoVaultEncrypt", js.FuncOf(VaultEncrypt))
	js.Global().Set("AxoVaultDecrypt", js.FuncOf(VaultDecrypt))

	js.Global().Set("AxoBoxGenerateKey", js.FuncOf(BoxGenerateKey))
	js.Global().Set("AxoBoxSeal", js.FuncOf(BoxSeal))
	js.Global().Set("AxoBoxUnseal", js.FuncOf(BoxUnseal))
	js.Global().Set("AxoBoxWrapKey", js.FuncOf(BoxWrapKey))
	js.Global().Set("AxoBoxUnwrapKey", js.FuncOf(BoxUnwrapKey))

	js.Global().Set("AxoUtilGenerateSalt", js.FuncOf(UtilGenerateSalt))

	js.Global().Set("AxoSignGenerateKey", js.FuncOf(SignGenerateKey))
	js.Global().Set("AxoSignMessage", js.FuncOf(SignMessage))
	js.Global().Set("AxoSignVerify", js.FuncOf(SignVerify))

	<-c
}
