// I think this is how you're supposed to implement RSA?
// IDK this is a web challenge not a crypto challenge :clown:
// I just picked 2 random prime numbers as the tutorial said
// (Or is it 0_0)

var p = 3217;
var q = 6451;
var e = 17;
// Hmmm, RSA calculator says to set these values
var N = p * q;
var phi = (p - 1) * (q - 1);
var d = 4880753;

function decryptRSA(num) {
	return modPow(num,d,N);
}

function checkPassword(password,pass) {
	var arr = pass.split(",");
	for(var i = 0;i < arr.length;++i) {
		arr[i] = parseInt(arr[i]);
	}
	if(arr.length != password.length) return false;
	console.log(arr.length);
	for(var i = 0;i < arr.length;++i) {
		var currentChar = password.charCodeAt(i);
		var currentInput = decryptRSA(arr[i]);
		if(currentChar != currentInput) return false;
	}
	return true;
}

function modPow(base,exp,mod) {
	var result = 1;
	for(var i = 0;i < exp;++i) { //relatively slow
		result = (result * base) % mod;
	}
	//most likely time analysis but still actually relativily fast for code which is sus
	// exp is 4 million, mod is like 2 million, base is like 
	return result;
}

module.exports = {checkPassword}