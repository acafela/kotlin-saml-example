package saml.example.idp

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.test.web.client.TestRestTemplate
import org.springframework.boot.test.web.client.getForEntity
import org.springframework.http.HttpStatus

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
class IntergrationTests(@Autowired val restTemplate: TestRestTemplate) {
    
    @Test
    fun `Assert blog page title, content and status code`() { // 표현적인 함수 이름을 사용하기 위해서 카멜표기법이 아닌 실제 문장을 backtick 기호 안에 넣음
        val entity = restTemplate.getForEntity<String>("/")
        assertThat(entity.statusCode).isEqualTo(HttpStatus.OK)
        assertThat(entity.body).contains("<h1>Blog</h1>")
//        assertThat(entity.body).contains("exception!!!!")
    }

}