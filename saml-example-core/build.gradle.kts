plugins {
    kotlin("jvm")
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    implementation(kotlin("reflect"))
    implementation("org.springframework.security.extensions:spring-security-saml2-core:1.0.10.RELEASE")
    implementation("org.opensaml:opensaml:2.6.4")

}