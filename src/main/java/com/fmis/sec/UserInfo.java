package com.fmis.sec;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserInfo {

	private String username;
    private String password;
    private String fullName;
    private String userId;
    private String companyId;
    private String companyName;
    
    private List<String> authorities;
    
}
