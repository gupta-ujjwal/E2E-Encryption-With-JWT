package com.signature.implementation.encryption.encrypt.model;

public class EncryptPayload {
	private String encryptedKey;
	private String encryptedPayload;
	private String tag;
	private String iv;
	private String rsaKeyId;

	public String getEncryptedPayload() {
		return encryptedPayload;
	}

	public void setEncryptedPayload(String encryptedPayload) {
		this.encryptedPayload = encryptedPayload;
	}

	public String getEncryptedKey() {
		return encryptedKey;
	}

	public void setEncryptedKey(String encryptedKey) {
		this.encryptedKey = encryptedKey;
	}

	public String getTag() {
		return tag;
	}

	public void setTag(String tag) {
		this.tag = tag;
	}

	public String getIv() {
		return iv;
	}

	public void setIv(String iv) {
		this.iv = iv;
	}

	public String getRsaKeyId() {
		return rsaKeyId;
	}

	public void setRsaKeyId(String rsaKeyId) {
		this.rsaKeyId = rsaKeyId;
	}

	@Override
	public String toString() {
		return "Payload [encryptedKey=" + encryptedKey + ", encryptedPayload=" + encryptedPayload + ", tag="
				+ tag + ", iv=" + iv + ", rsaKeyId=" + rsaKeyId + "]";
	}

}
