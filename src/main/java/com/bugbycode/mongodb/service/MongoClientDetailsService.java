package com.bugbycode.mongodb.service;

import java.util.List;

import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Service;

import com.bugbycode.mongodb.base.MongoSuportTemplate;

@Service("mongoClientDetailsService")
public class MongoClientDetailsService extends MongoSuportTemplate implements ClientDetailsService {

	private final String CONLLECTION_NAME = "oauth_client_details";
	
	public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
		BaseClientDetails client = mongoTemplate.findOne(new Query(Criteria.where("clientId").is(clientId)), BaseClientDetails.class, CONLLECTION_NAME);
//		if(client != null) {
//			String secret = client.getClientSecret();
//			if(!(secret == null || "".equals(secret))) {
//				client.setClientSecret(secret);
//			}
//		}
		return client;
	}

	public void addClientDetails(ClientDetails clientDetails) {
		mongoTemplate.insert(clientDetails, CONLLECTION_NAME);
	}
	
	public void updateClientDetails(ClientDetails clientDetails) {
		Update update = new Update();
		update.set("resourceIds", clientDetails.getResourceIds());
		update.set("clientSecret", clientDetails.getClientSecret());
		update.set("authorizedGrantTypes", clientDetails.getAuthorizedGrantTypes());
		update.set("registeredRedirectUris", clientDetails.getRegisteredRedirectUri());
		update.set("authorities", clientDetails.getAuthorities());
		update.set("accessTokenValiditySeconds", clientDetails.getAccessTokenValiditySeconds());
		update.set("refreshTokenValiditySeconds", clientDetails.getRefreshTokenValiditySeconds());
		update.set("additionalInformation", clientDetails.getAdditionalInformation());
		update.set("scope", clientDetails.getScope());
		mongoTemplate.updateFirst(new Query(Criteria.where("clientId").is(clientDetails.getClientId())), update, CONLLECTION_NAME);
	}
	
	public void updateClientSecret(String clientId, String secret) {
		Update update = new Update();
		update.set("clientSecret", secret);
		mongoTemplate.updateFirst(new Query(Criteria.where("clientId").is(clientId)), update, CONLLECTION_NAME);
	}
	
	public void removeClientDetails(String clientId) {
		mongoTemplate.remove(new Query(Criteria.where("clientId").is(clientId)), CONLLECTION_NAME);
	}
	
	public List<ClientDetails> listClientDetails(){
		return mongoTemplate.findAll(ClientDetails.class, CONLLECTION_NAME);
	}

}
