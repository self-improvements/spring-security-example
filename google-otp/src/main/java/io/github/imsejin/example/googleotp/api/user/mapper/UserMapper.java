package io.github.imsejin.example.googleotp.api.user.mapper;

import io.github.imsejin.example.googleotp.api.user.model.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface UserMapper {

    @Results({
            @Result(property = "id", column = "USER_ID"),
            @Result(property = "password", column = "PASSWORD"),
            @Result(property = "otpSecretKey", column = "OTP_SCT_KEY"),
            @Result(property = "name", column = "USER_NM"),
            @Result(property = "email", column = "EMAIL"),
            @Result(property = "createId", column = "CRT_ID"),
            @Result(property = "createDateTime", column = "CRT_DT"),
            @Result(property = "modifyId", column = "MDF_ID"),
            @Result(property = "modifyDateTime", column = "MDF_DT"),
    })
    @Select("""
            SELECT *
              FROM USERS
             WHERE USER_ID = #{id}
            """)
    User selectUserById(String id);

}
