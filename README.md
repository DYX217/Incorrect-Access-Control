# Incorrect-Access-Control
Description of an incorrect access control vulnerability of White-Jotter project v0.2.2.

White-Jotter s a simple front-end and back-end separation project with 2.5k stars on GitHub, has an incorrect access control vulnerability because of a config error in the file [ShiroConfiguration.java](https://github.com/Antabot/White-Jotter/blob/master/wj/src/main/java/com/gm/wj/config/ShiroConfiguration.java). The springboot backend usually uses Apache Shiro, a powerful and flexible Java security framework, to handle authentication and authorization. If it is not configured properly, unauthorized access may occur.

## Version
Favorites-web Project 0.2.2

## Attack Vector
In the white-jotter project, function shiroFilter in White-Jotter/wj/src/main/java/com/gm/wj/config/ShiroConfiguration.java code defines the mapping between URL matching rules and filter. Therefore, attackers can use directory traversal to carefully construct URLs to bypass the path matching rules in Shiro config that require authentication, thereby achieving unauthorized access.

## Vulnerability causes
function shiroFilter in ShiroConfiguration.java defines the mapping between URL matching rules and filter.

```java
public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        shiroFilterFactoryBean.setLoginUrl("/nowhere");

        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<String, String>();
        Map<String, Filter> customizedFilter = new HashMap<>();  // 自定义过滤器设置 1

        customizedFilter.put("url", getURLPathMatchingFilter()); // 自定义过滤器设置 2，命名，需在设置过滤路径前

        filterChainDefinitionMap.put("/api/authentication", "authc"); // 防鸡贼登录
        filterChainDefinitionMap.put("/api/menu", "authc");
        filterChainDefinitionMap.put("/api/admin/**", "authc");

        filterChainDefinitionMap.put("/api/admin/**", "url");  // 自定义过滤器设置 3，设置过滤路径

        shiroFilterFactoryBean.setFilters(customizedFilter); // 自定义过滤器设置 4，启用
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
}

```

`filterChainDefinitionMap.put` function implements the specific filter chain definition. 

1. `filterChainDefinitionMap.put("/api/authentication", "authc");` means that when accessing the path /api/authentication, you need to pass through the shiro built-in "authc" filter.
2. `filterChainDefinitionMap.put("/api/menu", "authc");` means that when accessing the path /api/menu, you need to pass through the shiro built-in "authc" filter.
3. `filterChainDefinitionMap.put("/api/admin/**", "authc");` means that when accessing all resources under the /api/admin/** path, you need to pass through the shiro built-in "authc" filter.
4. `filterChainDefinitionMap.put("/api/admin/**", "url");` means that when accessing all resources under the /api/admin/** path, you need to pass through the custom "url" filter.

So, we can use directory traversal to carefully construct URLs to bypass the path matching rules 3 and 4. For example, when accessing the path `/api/admin/content/article`, we should pass throuth shiro built-in "authc" filter and custom "url" filter. But if we change the path to `/api/aaa;/../admin/content/article`, it will not match the path matching rule `/api/admin/**` defined in the filterChainDefinitionMap, thus bypassing the filter authentication and access `/api/admin/content/article` successfully.

## Vulnerability reproduce
First, we find an interface that requires authentication to access, `/api/admin/content/article`. This API is used to uploud the article content.

Then, we tried to access this endpoint by Postman without authentication information. We can see that due to the lack of authentication information, there is no results returned.

![normal access](https://github.com/DYX217/directory-traversal/blob/main/image/normal.png)
