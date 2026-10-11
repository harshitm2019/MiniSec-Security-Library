package com.minisec.jwt;

import java.util.Map;

public interface JwtEncoder {

    String encode(Map<String, Object> claims);

}
