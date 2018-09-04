package com.bugbycode.module.token;

import java.io.Serializable;

public class OauthRefreshToken implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7859542192206638404L;
	
private String token_id;
	
	private byte[] token;
	
	private byte[] authentication;

	public String getToken_id() {
		return token_id;
	}

	public void setToken_id(String token_id) {
		this.token_id = token_id;
	}

	public byte[] getToken() {
		return token;
	}

	public void setToken(byte[] token) {
		this.token = token;
	}

	public byte[] getAuthentication() {
		return authentication;
	}

	public void setAuthentication(byte[] authentication) {
		this.authentication = authentication;
	}
}
