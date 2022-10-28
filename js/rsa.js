// rsa 加解密方法集
window.rsaUtil = {
	// rsa 的位数 （目前可以被破解的是768位，后面就没有破过了）
	_keySize: 1024,
	// rsa 的key, 即私钥（其中公钥其实是私钥的一部分而已）以xml的字符串形式存在，可以从内存上读取
	_rsaKeyStr: '',
	// 是否有加 padding 类型
	doOaepPadding: false,
	// 获取新的rsa provider
	getNewRsaProvider: function (dwKeySize) {
		// Create a new instance of RSACryptoServiceProvider.
		if (!dwKeySize) dwKeySize = this._keySize;
		return new System.Security.Cryptography.RSACryptoServiceProvider(dwKeySize);
	},
	// 重新生成新的rsa的key，并将私钥的值存在本地存储
	setNewRsaKey: function(){
		var rsa = this.getNewRsaProvider();
		this._rsaKeyStr = rsa.ToXmlString(true);
		return this._rsaKeyStr;
	},
	// 获取rsa key
	getRsaKey: function (includePrivateParameters, rsaKeyStr) {
		var rsa = this.getNewRsaProvider();
		// Import parameters from xml.
		// 直接把key传过去，他会提取里面的信息，包括是否有公钥或者私钥的信息
		rsa.FromXmlString(rsaKeyStr);
		// Export RSA key to RSAParameters and include:
		//    false - 加密过程，只要传公钥就行了，即上面的 rsaKeyStr 要有公钥信息
		//    true  - 解密过程，要传私钥，即上面的 rsaKeyStr 要有私钥信息
		return rsa.ExportParameters(includePrivateParameters);
	},
	// 进行rsa加密
	encrypt: function(bytes, publishKey){
		var doOaepPadding = this.doOaepPadding;
		// 如果没有传公钥，就相当于使用自己的公钥
		publishKey = publishKey || this._rsaKeyStr;
		var rsa = this.getNewRsaProvider();
		// Import the RSA Key information.
		rsa.ImportParameters(this.getRsaKey(false,publishKey));
		// Encrypt the passed byte array and specify OAEP padding.
		return rsa.Encrypt(bytes, doOaepPadding);
	},
	// 进行rsa加密并转化为base64输出
	encryptToBase64: function(data,publishKey){
		var bytes = System.Text.Encoding.UTF8.GetBytes(data);
		var encryptedBytes = this.encrypt(bytes,publishKey);
		return System.Convert.ToBase64String(encryptedBytes);
	},
	// rsa 解密
	decrypt: function(bytes){
		var doOaepPadding = this.doOaepPadding;
		var rsa = this.getNewRsaProvider();
		// Import the RSA Key information.
		rsa.ImportParameters(this.getRsaKey(true,this._rsaKeyStr));
		// Decrypt the passed byte array and specify OAEP padding.
		return rsa.Decrypt(bytes, doOaepPadding);
	},
	// 进行rsa解密并转化为base64输出
	decryptToBase64: function(data){
		var encryptedBytes = System.Convert.FromBase64String(data);
		var decryptedBytes = this.decrypt(encryptedBytes);
		return System.Text.Encoding.UTF8.GetString(decryptedBytes);
	},
	// 获取公钥（从私钥，也就是key中提取出来）
	getPublishKey: function(){
		return this._rsaKeyStr.replace(/(<\/Exponent>)(\S+)(<\/RSAKeyValue>)/gm,'$1$3');
	},
	// 获取私钥，其实就是key
	getPrivateKey: function(){
		return this._rsaKeyStr;
	},
	// 设置key
	setRsaKeyValue: function(str){
		this._rsaKeyStr = str;
	},
	// 设置 位数
	setKeySize: function(str){
		this._keySize = parseInt(str);
	},
	// 设置 padding 方式
	setPadding: function(padding){
		this.doOaepPadding = padding;
	}
};