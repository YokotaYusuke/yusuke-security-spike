package com.example.yusukesecurityspike

import jakarta.persistence.*
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.datasource.DriverManagerDataSource
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.NoOpPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
import org.springframework.security.provisioning.JdbcUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import javax.sql.DataSource

@Configuration
@EnableWebSecurity
class SecurityConfig {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .authorizeHttpRequests {
                it.requestMatchers("/").permitAll()
                it.anyRequest().authenticated()
            }
            .formLogin{}
        return http.build()
    }

    @Bean
    fun userDetailsService(dataSource: DataSource): UserDetailsService {
        val user = User.builder()
            .username("user")
            .password("{bcrypt}$2a$10\$ofhSMQ38QHWK3aCOZvAK.eneoaAnSHAFc0M48ud7Xyig3H8KUwUOm")
            .roles("USER")
            .build()

        val myUser = MyUser("user1", "{noop}password", true, mutableListOf(Authority("user1", "USER")))
        val myUser2 = MyUser.builder()
            .username("user2")
            .password("{noop}password")
            .authorities("USER")
            .build()
        val users = JdbcUserDetailsManager(dataSource)
        users.createUser(user)
        users.createUser(myUser2)
        return users
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        val idFOrEncode = "bcrypt"
        val encoders: MutableMap<String, PasswordEncoder> = mutableMapOf()
        encoders[idFOrEncode] = BCryptPasswordEncoder()
        encoders["argon2"] = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        encoders["pbkdf2"] = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        encoders["noop"] = NoOpPasswordEncoder.getInstance()
        return DelegatingPasswordEncoder(idFOrEncode, encoders)
    }

    @Value("\${spring.datasource.url}")
    private lateinit var datasourceUrl: String

    @Value("\${spring.datasource.username}")
    private lateinit var datasourceUsername: String

    @Value("\${spring.datasource.password}")
    private lateinit var datasourcePassword: String

    @Value("\${spring.datasource.driver-class-name}")
    private lateinit var datasourceDriverClassName: String

    @Bean
    fun dataSource(): DataSource {
        val dataSource = DriverManagerDataSource()
        dataSource.setDriverClassName(datasourceDriverClassName)
        dataSource.url = datasourceUrl
        dataSource.username = datasourceUsername
        dataSource.password = datasourcePassword
        return dataSource
    }
}

@Entity
@Table(name = "users")
data class MyUser(
    @Id
    @Column(length = 50)
    private var username: String,

    @Column(length = 500)
    private var password: String,

    private var enabled: Boolean,

    @OneToMany
    @JoinColumn(name = "username")
    var authorities: MutableList<Authority> = mutableListOf()
): UserDetails {
    override fun getAuthorities(): Collection<GrantedAuthority> = authorities
    override fun getPassword(): String = password
    override fun getUsername(): String = username
    override fun isAccountNonExpired(): Boolean = true
    override fun isAccountNonLocked(): Boolean = true
    override fun isCredentialsNonExpired(): Boolean = true
    override fun isEnabled(): Boolean = enabled

    companion object {
        fun builder(): MyUserBuilder {
            return MyUserBuilder()
        }
    }

    class MyUserBuilder {
        private var username: String = ""
        private var password: String = ""
        private var enabled: Boolean = true
        private var authorities: List<String> = emptyList()

        fun username(newValue: String): MyUserBuilder {
            username = newValue
            return this
        }

        fun password(newValue: String): MyUserBuilder {
            password = newValue
            return this
        }

        fun enabled(newValue: Boolean): MyUserBuilder {
            enabled = newValue
            return this
        }

        fun authorities(vararg values: String): MyUserBuilder {
            authorities = listOf(*values)
            return this
        }

        fun build(): MyUser {
            return MyUser(
                username,
                password,
                enabled,
                authorities.map { Authority(username, "ROLE_$it") }.toMutableList()
            )
        }
    }
}

@Entity
@Table(name = "authorities")
@IdClass(AuthorityId::class)
data class Authority(
    @Id
    var username: String,

    @Id
    @Column(name = "authority" ,length = 50)
    val authorityString: String
): GrantedAuthority {
    override fun getAuthority(): String = authorityString
}

data class AuthorityId(
    var username: String,
    var authorityString: String
) : java.io.Serializable
