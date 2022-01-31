package com.afm.authservice.controller;


import com.afm.authservice.service.AuthenticationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import lombok.RequiredArgsConstructor;
import model.auth.AuthProvider;
import model.auth.ERole;
import model.auth.UserBas;
import model.utils.LoginRequest;
import model.utils.TokenDto;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.social.facebook.api.Facebook;
import org.springframework.social.facebook.api.User;
import org.springframework.social.facebook.api.impl.FacebookTemplate;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin
@RequestMapping("/oauth")
@RequiredArgsConstructor
public class OauthController {
    private final AuthenticationService authenticationService;
    private static Logger logger = LoggerFactory.getLogger(OauthController.class);

    @Value("${spring.security.oauth2.client.registration.google.clientId}")
    String googleClientId;

    @Value("${spring.security.oauth2.client.registration.facebook.clientId}")
    String facebookClientId;

    @Value("${security.pswExtUser}")
    String pswExtUser;


    @PostMapping("/google")
    public UserBas google(@RequestBody TokenDto tokenGoogle) throws Exception {
        final NetHttpTransport netHttpTransport = new NetHttpTransport();
        final JsonFactory JSON_FACTORY = GsonFactory.getDefaultInstance();

        GoogleIdTokenVerifier.Builder verifier
                = new GoogleIdTokenVerifier.Builder(netHttpTransport, JSON_FACTORY)
                .setAudience(Collections.singleton(googleClientId));

        final GoogleIdToken googleToken = GoogleIdToken.parse(verifier.getJsonFactory(), tokenGoogle.getValue());
        final GoogleIdToken.Payload payload = googleToken.getPayload();

        if(!authenticationService.exisitUser(payload.getEmail())){
            LoginRequest credentials = new LoginRequest(payload.getEmail(), pswExtUser);
            authenticationService.createUser(credentials, AuthProvider.google, ERole.USER);
        }

        logger.info("Login with google for " + payload.getEmail());
        return authenticationService.findUser(payload.getEmail());
    }

    @PostMapping("/facebook")
    public UserBas facebook(@RequestBody TokenDto tokenFacebook) throws Exception {
        Facebook facebook = new FacebookTemplate(tokenFacebook.getValue());
        final String [] fields = {"email", "name"};
        User user = facebook.fetchObject("me", User.class, fields);

        if(!authenticationService.exisitUser(user.getEmail())){
            LoginRequest credentials = new LoginRequest(user.getEmail(), pswExtUser);
            authenticationService.createUser(credentials, AuthProvider.facebook, ERole.USER);
        }
        logger.info("Login with facebook for " + user.getEmail());
        return authenticationService.findUser(user.getEmail());
    }


    @PostMapping("/amazon")
    public UserBas amazon(@RequestBody TokenDto tokenAmazon) throws IOException, Exception {
        HttpGet request = new HttpGet("https://api.amazon.com/user/profile");
        request.addHeader("Authorization", "bearer " + tokenAmazon.getValue());

        CloseableHttpClient httpClient = HttpClients.createDefault();
        CloseableHttpResponse response = httpClient.execute(request);
        HttpEntity entity = response.getEntity();

        String result = EntityUtils.toString(entity);
        Map<String,String> detailUser =
                new ObjectMapper().readValue(result, HashMap.class);

        if(!authenticationService.exisitUser(detailUser.get("email"))){
            LoginRequest credentials = new LoginRequest(detailUser.get("email"), pswExtUser);
            authenticationService.createUser(credentials, AuthProvider.amazon, ERole.USER);
        }
        logger.info("Login with Amazon for " + detailUser.get("email"));
        return authenticationService.findUser(detailUser.get("email"));

    }




}
