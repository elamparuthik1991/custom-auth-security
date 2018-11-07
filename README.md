# custom auth security
custom auth security with multiple header request.

## 1. Configuration WebConfig.java
We need to include the following "WebConfig.java" file. 

```java
import org.springframework.boot.autoconfigure.web.DispatcherServletAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import com.haroob.noor.logger.LoggableDispatcherServlet;
import com.haroob.noor.security.SessionManager;

@Configuration
public class WebConfig extends WebMvcConfigurerAdapter {
	
	@Bean(name = DispatcherServletAutoConfiguration.DEFAULT_DISPATCHER_SERVLET_BEAN_NAME)
	public DispatcherServlet dispatcherServlet() {
		return new LoggableDispatcherServlet();
	}

	@Bean
	SessionManager getSessionManager() {
		return new SessionManager();
	}
	
	@Override
	public void addInterceptors(InterceptorRegistry registry) {
		registry.addInterceptor(getSessionManager())
				.addPathPatterns("/api/v1/**/invoices", "/api/v1/**/invoice/**", "/api/v1/**/transactions",
						"/api/v1/**/**/makePayment", "/api/v1/**/transfer", "/api/v1/**/logout",
						"/api/v1/**/customer-details", "/api/v1/**/customer-banks")
				.excludePathPatterns("/api/v1/tranactions/**");
		// assuming you put your serve your static files with /resources/ mapping
		// and the pre login page is served with /login mapping
	}

}
```
## 2. Configuration SessionManager.java
We need to include the following "SessionManager.java" file.

```java
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import com.haroob.noor.model.AppRegistration;
import com.haroob.noor.repository.AppRegistrationRepository;

public class SessionManager implements HandlerInterceptor {

	@Autowired
	private AppRegistrationRepository appRegistrationRepository;

	// This method is called before the controller
	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		String sessionId = request.getHeader("SessionId");
		String deviceId = request.getHeader("DeviceId");
		
		String servletPath = request.getRequestURI();

		String errorPath = new String();
		if (servletPath.contains("/noor-payments/")) {
			errorPath = "/noor-payments/api/v1/401";
		} else {
			errorPath = "/api/v1/401";
		}

		String[] split = servletPath.split("/api/v1/");
		String[] noor = split[1].split("/");
		String noorAccountNumber = noor[0];

		if (sessionId == null || deviceId == null) {
			response.sendRedirect(errorPath);
			return false;
		} else if (sessionId.equals("") || deviceId.equals("")) {
			response.sendRedirect(errorPath);
			return false;
		}

		AppRegistration appRegistration = new AppRegistration();

		try {
			appRegistration = appRegistrationRepository.checkDeviceIdSessionIdAvailablity(deviceId, sessionId);
		} catch (Exception e1) {
			// TODO: handle exception
			e1.printStackTrace();
			response.sendRedirect(errorPath);
			return false;
		}

		if (appRegistration == null) {
			response.sendRedirect(errorPath);
			return false;
		}
		if (!appRegistration.getSessionId().equals(sessionId) || !appRegistration.getDeviceId().equals(deviceId)
				|| !servletPath.contains(appRegistration.getNoorAccountNumber())) {
			response.sendRedirect(errorPath);
			return false;
		} else {
			return true;
		}

	}

	@Override
	public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
			ModelAndView modelAndView) throws Exception {

	}

	@Override
	public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex)
			throws Exception {
	}
}
```
## Controller
```java
	@GetMapping("/401/{language}")
	public ResponseEntity<Result> authError(@PathVariable(name = "language") String lang) {
		Result result = new Result();
		result.setStatus("unauthorized");
		result.setMessage(resource.getMessage("auth.error", null, new Locale(lang)));
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(result);
	}
```
## Conclusion
End of this integration you may find auth.
### Header need to be passed
1. SessionId.
2. DeviceId.
In header of all APIs

## References
To make edit this document please use [edit readme.md](https://www.makeareadme.com/#rendered-1).
