package net.norskel.auth.module.runtime.entities;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.time.OffsetDateTime;
import java.util.UUID;

/**
 * The type User entity.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserEntity {

    /**
     * The Username.
     */
    @NotBlank()
    @Schema(example = "testusername")
    @JsonProperty(value = "username")
    protected String username;

    /**
     * The Name.
     */
    @JsonProperty(value = "name")
    protected String name;

    /**
     * The Email.
     */
    @NotBlank()
    @Schema(example = "test@example.fr")
    @JsonProperty(value = "email")
    protected String email;

    /**
     * The Role.
     */
    @NotBlank()
    @Schema(example = "hermes_user")
    @JsonProperty(value = "role")
    protected String role = "admin";

    /**
     * The Gitlab id.
     */
    @NotNull()
    @Schema(examples = "42")
    @JsonProperty(value = "oidc_id")
    protected String oidcId;

    /**
     * The Avatar url.
     */
    @JsonProperty(value = "avatar_url")
    protected String avatarUrl;

    /**
     * The State.
     */
    @Schema(readOnly = true, examples = "ACTIVE")
    @JsonProperty(value = "state")
    protected UserStateEnum state;

    /**
     * The Id.
     */
    @Schema(readOnly = true)
    @JsonProperty(value = "id")
    private UUID id;

    /**
     * The Created at.
     */
    @Schema(readOnly = true)
    @JsonProperty(value = "created_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    private OffsetDateTime createdAt;

    /**
     * The Last login.
     */
    @Schema(readOnly = true)
    @JsonProperty(value = "last_login")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    private OffsetDateTime lastLogin;
}
