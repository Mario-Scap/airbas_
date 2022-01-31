package model.auth;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;
import java.util.List;

@Getter
@Setter
@Entity
@ToString
@Table(name = "userbas")
public class UserBas {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;
    private String password;
    private Boolean enabled;

    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "userbas_authorities",
            joinColumns = {@JoinColumn(name = "userbas_id", referencedColumnName = "id")},
            inverseJoinColumns = {@JoinColumn(name = "authorities_id", referencedColumnName = "id")})
    private List<Authority> authorities;

    /*@OneToOne(mappedBy = "userbas", fetch = FetchType.LAZY,
            cascade = CascadeType.ALL)
    @JsonManagedReference
    private UserBasDetail userbasdetail;*/

}
