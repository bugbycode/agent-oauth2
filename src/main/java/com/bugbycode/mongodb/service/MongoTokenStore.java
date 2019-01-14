package com.bugbycode.mongodb.service;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.SerializationUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

import com.bugbycode.module.token.OauthAccessToken;
import com.bugbycode.module.token.OauthRefreshToken;
import com.bugbycode.mongodb.base.MongoSuportTemplate;

@Service("mongoTokenStore")
public class MongoTokenStore extends MongoSuportTemplate implements TokenStore {

	private final Logger logger = LogManager.getLogger(MongoTokenStore.class);
	
	private final String TOKEN_CONLLECTION_NAME = "oauth_access_token";
	
	private final String TOKEN_REFRESH_CONLLECTION_NAME = "oauth_refresh_token";
	
	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	public AuthenticationKeyGenerator getAuthenticationKeyGenerator() {
		return authenticationKeyGenerator;
	}

	public void setAuthenticationKeyGenerator(AuthenticationKeyGenerator authenticationKeyGenerator) {
		this.authenticationKeyGenerator = authenticationKeyGenerator;
	}

	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}

	public OAuth2Authentication readAuthentication(String token) {
		OAuth2Authentication authentication = null;
		try {
			OauthAccessToken oauthAccessToken = mongoTemplate.findOne(new Query(Criteria.where("token_id").is(extractTokenKey(token))), OauthAccessToken.class,TOKEN_CONLLECTION_NAME);
			if(oauthAccessToken != null) {
				authentication = deserializeAuthentication(oauthAccessToken.getAuthentication());
			}
		}catch (Exception e) {
			removeAccessToken(token);
			logger.error(e.getLocalizedMessage());
		}
		return authentication;
	}

	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		String refreshToken = null;
		if (token.getRefreshToken() != null) {
			refreshToken = token.getRefreshToken().getValue();
		}
		
		if (readAccessToken(token.getValue())!=null) {
			removeAccessToken(token.getValue());
		}
		
		OauthAccessToken oauthAccessToken = new OauthAccessToken();
		oauthAccessToken.setToken_id(extractTokenKey(token.getValue()));
		oauthAccessToken.setToken(serializeAccessToken(token));
		oauthAccessToken.setAuthentication_id(authenticationKeyGenerator.extractKey(authentication));
		oauthAccessToken.setUser_name(authentication.isClientOnly() ? null : authentication.getName());
		oauthAccessToken.setClient_id(authentication.getOAuth2Request().getClientId());
		oauthAccessToken.setAuthentication(serializeAuthentication(authentication));
		oauthAccessToken.setRefresh_token(extractTokenKey(refreshToken));
		
		mongoTemplate.insert(oauthAccessToken, TOKEN_CONLLECTION_NAME);
	}

	public OAuth2AccessToken readAccessToken(String tokenValue) {
		OAuth2AccessToken accessToken = null;
		try {
			OauthAccessToken oauthAccessToken = mongoTemplate.findOne(new Query(Criteria.where("token_id").is(extractTokenKey(tokenValue))), OauthAccessToken.class,TOKEN_CONLLECTION_NAME);
			if(oauthAccessToken != null) {
				accessToken = deserializeAccessToken(oauthAccessToken.getToken());
			}
		}catch (Exception e) {
			logger.error(e.getLocalizedMessage());
			removeAccessToken(tokenValue);
		}
		return accessToken;
	}

	public void removeAccessToken(OAuth2AccessToken token) {
		removeAccessToken(token.getValue());
	}
	
	public void removeAccessToken(String tokenValue) {
		mongoTemplate.remove(new Query(Criteria.where("token_id").is(extractTokenKey(tokenValue))), TOKEN_CONLLECTION_NAME);
	}

	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		OauthRefreshToken oauthRefreshToken = new OauthRefreshToken();
		oauthRefreshToken.setToken_id(extractTokenKey(refreshToken.getValue()));
		oauthRefreshToken.setToken(serializeRefreshToken(refreshToken));
		oauthRefreshToken.setAuthentication(serializeAuthentication(authentication));
		
		mongoTemplate.insert(oauthRefreshToken, TOKEN_REFRESH_CONLLECTION_NAME);
	}

	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		OAuth2RefreshToken refreshToken = null;
		try {
			OauthRefreshToken oauthRefreshToken = mongoTemplate.findOne(new Query(Criteria.where("token_id").is(extractTokenKey(tokenValue))), OauthRefreshToken.class, TOKEN_REFRESH_CONLLECTION_NAME);
			if(oauthRefreshToken != null) {
				refreshToken = deserializeRefreshToken(oauthRefreshToken.getToken());
			}
		}catch (Exception e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
			removeRefreshToken(tokenValue);
		}
		return refreshToken;
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return readAuthenticationForRefreshToken(token.getValue());
	}
	
	public OAuth2Authentication readAuthenticationForRefreshToken(String value) {
		OAuth2Authentication authentication = null;
		try {
			OauthRefreshToken oauthRefreshToken = mongoTemplate.findOne(new Query(Criteria.where("token_id").is(extractTokenKey(value))), OauthRefreshToken.class, TOKEN_REFRESH_CONLLECTION_NAME);
			if(oauthRefreshToken == null) {
				throw new RuntimeException("Failed to find refresh token for token " + value);
			}
			authentication = deserializeAuthentication(oauthRefreshToken.getAuthentication());
		}catch (Exception e) {
			logger.error(e.getLocalizedMessage());
			removeRefreshToken(value);
		}
		return authentication;
	}

	public void removeRefreshToken(OAuth2RefreshToken token) {
		removeRefreshToken(token.getValue());
	}

	public void removeRefreshToken(String token) {
		mongoTemplate.remove(new Query(Criteria.where("token_id").is(extractTokenKey(token))), TOKEN_REFRESH_CONLLECTION_NAME);
	}
	
	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		removeAccessTokenUsingRefreshToken(refreshToken.getValue());
	}
	
	public void removeAccessTokenUsingRefreshToken(String refreshToken) {
		mongoTemplate.remove(new Query(Criteria.where("refresh_token").is(extractTokenKey(refreshToken))), TOKEN_CONLLECTION_NAME);
	}

	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		String key = authenticationKeyGenerator.extractKey(authentication);
		OAuth2AccessToken accessToken = null;
		try {
			OauthAccessToken oauthAccessToken = mongoTemplate.findOne(new Query(Criteria.where("authentication_id").is(key)), OauthAccessToken.class, TOKEN_CONLLECTION_NAME);
			if(oauthAccessToken != null) {
				accessToken = deserializeAccessToken(oauthAccessToken.getToken());
			}
		}catch (Exception e) {
			e.printStackTrace();
			logger.error(e.getLocalizedMessage());
		}
		if (accessToken != null
				&& !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
			removeAccessToken(accessToken.getValue());
			storeAccessToken(accessToken, authentication);
		}
		return accessToken;
	}

	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		Query query = new Query();
		query.addCriteria(Criteria.where("client_id").is(clientId));
		query.addCriteria(Criteria.where("user_name"));
		List<OauthAccessToken> tokenList = mongoTemplate.findAllAndRemove(query, OauthAccessToken.class, TOKEN_CONLLECTION_NAME);

		Collection<OAuth2AccessToken> collection = new ArrayList<OAuth2AccessToken>();
		if(!(tokenList == null || tokenList.isEmpty())) {
			for(OauthAccessToken oauthAccessToken : tokenList) {
				collection.add(deserializeAccessToken(oauthAccessToken.getToken()));
			}
		}
		return collection;
	}

	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		Query query = new Query();
		query.addCriteria(Criteria.where("client_id").is(clientId));
		List<OauthAccessToken> tokenList = mongoTemplate.findAllAndRemove(query, OauthAccessToken.class, TOKEN_CONLLECTION_NAME);
		Collection<OAuth2AccessToken> collection = new ArrayList<OAuth2AccessToken>();
		if(!(tokenList == null || tokenList.isEmpty())) {
			for(OauthAccessToken oauthAccessToken : tokenList) {
				collection.add(deserializeAccessToken(oauthAccessToken.getToken()));
			}
		}
		return collection;
	}
	
	protected byte[] serializeAccessToken(OAuth2AccessToken token) {
		return SerializationUtils.serialize(token);
	}

	protected byte[] serializeRefreshToken(OAuth2RefreshToken token) {
		return SerializationUtils.serialize(token);
	}

	protected byte[] serializeAuthentication(OAuth2Authentication authentication) {
		return SerializationUtils.serialize(authentication);
	}

	protected OAuth2AccessToken deserializeAccessToken(byte[] token) {
		return SerializationUtils.deserialize(token);
	}

	protected OAuth2RefreshToken deserializeRefreshToken(byte[] token) {
		return SerializationUtils.deserialize(token);
	}

	protected OAuth2Authentication deserializeAuthentication(byte[] authentication) {
		return SerializationUtils.deserialize(authentication);
	}

	protected String extractTokenKey(String value) {
		if (value == null) {
			return null;
		}
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).");
		}

		try {
			byte[] bytes = digest.digest(value.getBytes("UTF-8"));
			return String.format("%032x", new BigInteger(1, bytes));
		}
		catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).");
		}
	}

}
