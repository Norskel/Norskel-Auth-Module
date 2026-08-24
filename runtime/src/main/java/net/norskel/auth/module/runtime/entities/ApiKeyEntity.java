package net.norskel.auth.module.runtime.entities;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.time.OffsetDateTime;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiKeyEntity {

    @Schema(readOnly = true)
    @JsonProperty(value = "id")
    private UUID id;

    @NotBlank(message = "Api key need a name")
    @JsonProperty(value = "name")
    private String name;

    @Schema(readOnly = true)
    @JsonProperty(value = "revoked")
    @Builder.Default
    private Boolean revoked = false;

    /**
     * Owning user. Always set: a service key is owned by a {@code UserEntity}
     * of type {@code SERVICE}, so there is no second kind of key and no
     * discriminator to get wrong.
     */
    @Schema(examples = "1")
    @JsonProperty(value = "user_id")
    private UUID userId;

    @Schema(examples = "2027-07-18T09:41:40.669+02:00")
    @JsonProperty(value = "expires_at")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    private OffsetDateTime expiresAt;

    /**
     * Which identity issued this key.
     *
     * <p>Provenance, not ownership: for a self-issued key it equals
     * {@link #userId}, for a service key it is the admin who minted it. Read-only
     * over HTTP so a client cannot forge it.
     */
    @Schema(readOnly = true)
    @JsonProperty(value = "created_by", access = JsonProperty.Access.READ_ONLY)
    private UUID createdBy;

    @Schema(readOnly = true)
    @JsonProperty(value = "created_at", access = JsonProperty.Access.READ_ONLY)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    private OffsetDateTime createdAt;

    @Schema(readOnly = true)
    @JsonProperty(value = "last_used_at", access = JsonProperty.Access.READ_ONLY)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    private OffsetDateTime lastUsedAt;

    @Schema(readOnly = true)
    @JsonProperty(value = "revoked_at", access = JsonProperty.Access.READ_ONLY)
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
    private OffsetDateTime revokedAt;

}
