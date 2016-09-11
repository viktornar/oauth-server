package lt.geostream.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lt.geostream.security.GoogleProfile;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

import static com.google.common.collect.Lists.newArrayList;

@Component
@RequestMapping("find")
public class UserResource {
    private static ObjectMapper OM = new ObjectMapper();
    private final OAuth2RestOperations oauth2RestTemplate;
    private String userInfoUrl;

    @Autowired
    public UserResource(OAuth2RestOperations oauth2RestTemplate, @Value("google.userInfo") String userInfoUrl) {
        this.oauth2RestTemplate = oauth2RestTemplate;
        this.userInfoUrl = userInfoUrl;
    }

    @RequestMapping(method = RequestMethod.GET)
    public @ResponseBody
    List<String> findUsersStartingWithPrefix(@RequestParam("term") String usernamePrefix) throws JsonProcessingException {
        List<String> list = newArrayList();
        GoogleProfile profile = getGoogleProfile();
        list.add(profile.getName());
        list.add(profile.getEmail());
        return list;
    }

    private GoogleProfile getGoogleProfile() {
        String url = userInfoUrl + oauth2RestTemplate.getAccessToken();
        ResponseEntity<GoogleProfile> forEntity = oauth2RestTemplate.getForEntity(url, GoogleProfile.class);
        return forEntity.getBody();
    }
}
