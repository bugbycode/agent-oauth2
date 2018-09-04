package com.bugbycode.config;

import javax.annotation.Resource;
import javax.sql.DataSource;

import org.apache.commons.dbcp2.BasicDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.MongoDbFactory;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.SimpleMongoDbFactory;

import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;

@Configuration
public class DataSourceConfig {
	
	@Value("${spring.mongodb.uri}")
	private String mongoUri;
	
	/*
	@Bean("dataSource")
	@ConfigurationProperties(prefix="spring.datasource")
	public DataSource getDataSource() {
		return DataSourceBuilder.create(BasicDataSource.class.getClassLoader()).build();
	}*/
	
	@Bean("mongoDbFactory")
	public MongoDbFactory getMongoDbFactory() {
		return new SimpleMongoDbFactory(new MongoClientURI(mongoUri));
		//return new SimpleMongoDbFactory(new MongoClient(new MongoClientURI(mongoUri)), mongoDatabase);
	}
	
	@Bean("mongoTemplate")
	@Resource(name="mongoDbFactory")
	public MongoTemplate getMongoTemplate(MongoDbFactory mongoDbFactory) {
		return new MongoTemplate(mongoDbFactory);
	}
}
