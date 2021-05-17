package com.example.ids.db;


import com.zaxxer.hikari.HikariDataSource;
//import com.mysql.jdbc.jdbc2.optional.MysqlDataSource;
import com.mysql.cj.jdbc.MysqlDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import javax.sql.DataSource;
import java.sql.SQLException;


@Configuration
//@EnableJpaRepositories(
//        basePackages = "demo.sdr")
public class DbJPAConfiguration {

    @Bean
    public DataSource dataSource() throws SQLException {
    	MysqlDataSource dataSource = new MysqlDataSource();
        dataSource.setUser("springuser");
        dataSource.setPassword("password123");
        dataSource.setURL("jdbc:mysql://localhost:3306/ids");

//        dataSource.setFastConnectionFailoverEnabled(true);
        HikariDataSource hikariDataSource = new HikariDataSource();
        hikariDataSource.setDataSource(dataSource);
        return hikariDataSource;
    }

}













