package saml.example.core

import java.util.*

class SAMLAttribute {
    val name: String
    val values: List<String>

    constructor(name: String, values: List<String>) {
        this.name = name
        this.values = values
    }

    constructor(name: String, value: String) {
        this.name = name
        values = Arrays.asList(value)
    }

    val value: String
        get() = java.lang.String.join(", ", values)

    override fun toString(): String {
        return "SAMLAttribute{name='$name', values=$values}"
    }
}