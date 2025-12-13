//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"

	"github.com/axosec/core/crypto/box"
	"github.com/axosec/core/crypto/hash"
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

	encrypted, err := vault.Encrypt(data, key)
	if err != nil {
		return returnError(err)
	}
	return bytesToJS(encrypted)
}

func VaultDecrypt(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return returnError(fmt.Errorf("expected 2 arguments: data, key"))
	}
	data := jsToBytes(args[0])
	key := jsToBytes(args[1])

	decrypted, err := vault.Decrypt(data, key)
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

	sealed, err := box.Seal(data, peerPub)
	if err != nil {
		return returnError(err)
	}
	return bytesToJS(sealed)
}

func BoxUnseal(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return returnError(fmt.Errorf("expected 2 arguments: data, myPriv"))
	}
	data := jsToBytes(args[0])
	myPrivBytes := jsToBytes(args[1])

	myPriv, err := box.LoadPrivateKey(myPrivBytes)
	if err != nil {
		return returnError(err)
	}

	plaintext, err := box.Unseal(data, myPriv.Private)
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

	wrapped, err := box.WrapKey(keyToShare, peerPub)
	if err != nil {
		return returnError(err)
	}
	return bytesToJS(wrapped)
}

func BoxUnwrapKey(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return returnError(fmt.Errorf("expected 2 arguments: wrappedBlob, myPriv"))
	}
	blob := jsToBytes(args[0])
	myPrivBytes := jsToBytes(args[1])

	myPriv, err := box.LoadPrivateKey(myPrivBytes)
	if err != nil {
		return returnError(err)
	}

	key, err := box.UnwrapKey(blob, myPriv.Private)
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

	<-c
}
