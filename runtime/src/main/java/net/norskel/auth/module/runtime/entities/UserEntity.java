package net.norskel.auth.module.runtime.entities;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import net.norskel.auth.module.runtime.enums.UserStateEnum;
import net.norskel.auth.module.runtime.enums.UserTypeEnum;
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
     *
     * <p>Required for {@link UserTypeEnum#HUMAN}, always {@code null} for
     * {@link UserTypeEnum#SERVICE}. Enforced in {@code UserServiceImpl} rather
     * than by bean validation, which cannot express "required only for one
     * type".
     */
    @Schema(example = "test@example.fr")
    @JsonProperty(value = "email")
    protected String email;

    /**
     * The Role.
     */
    @NotBlank()
    @Schema(example = "hermes_user")
    @JsonProperty(value = "role")
    protected String role;

    /**
     * Subject claim from the identity provider.
     *
     * <p>Required for {@link UserTypeEnum#HUMAN}, and necessarily {@code null}
     * for {@link UserTypeEnum#SERVICE}: a service never logs in through OIDC.
     * See {@code UserServiceImpl} for the check.
     */
    @Schema(examples = "42")
    @JsonProperty(value = "oidc_id")
    protected String oidcId;

    /**
     * The Avatar url.
     */
    @JsonProperty(value = "avatar_url")
    protected String avatarUrl;

    /**
     * Whether this row is a person or a machine caller.
     */
    @Schema(examples = "HUMAN")
    @JsonProperty(value = "type")
    @Builder.Default
    protected UserTypeEnum type = UserTypeEnum.HUMAN;

    /**
     * The State. Defaults to {@link UserStateEnum#ACTIVE}; setting it to
     * {@link UserStateEnum#BLOCKED} disables every API key the row owns, for
     * services exactly as for people.
     */
    @Schema(readOnly = true, examples = "ACTIVE")
    @JsonProperty(value = "state")
    @Builder.Default
    protected UserStateEnum state = UserStateEnum.ACTIVE;

    /**
     * The Id.
     */
    @Schema(readOnly = true)
    @JsonProperty(value = "id")
    private UUID id;

    /**
     * Which identity created this row.
     *
     * <p>{@code null} for a person who self-created through OIDC. For a
     * {@code SERVICE} row it names the admin responsible, which is the audit
     * trail that lets you find the services a departing admin left behind.
     * Read-only over HTTP so a client cannot forge it.
     */
    @Schema(readOnly = true)
    @JsonProperty(value = "created_by", access = JsonProperty.Access.READ_ONLY)
    private UUID createdBy;

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
