package io.github.susimsek.springauthorizationserver.h2;

import jakarta.servlet.Servlet;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.SQLException;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@UtilityClass
@Slf4j
public class H2ConfigurationHelper {

    public static Object createServer(String port) throws SQLException {
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            Class<?> serverClass = Class.forName("org.h2.tools.Server", true, loader);
            Method createServer = serverClass.getMethod("createTcpServer", String[].class);
            return createServer.invoke(null, (Object) new String[]{"-tcp", "-tcpAllowOthers", "-tcpPort", port});
        } catch (ClassNotFoundException | LinkageError | NoSuchMethodException | IllegalAccessException e) {
            log.error("Failed to initialize H2 database server", e);
            throw new IllegalStateException("Failed to initialize H2 database server", e);
        } catch (InvocationTargetException e) {
            Throwable t = e.getTargetException();
            if (t instanceof SQLException sqlException) {
                throw sqlException;
            }
            log.error("Unchecked exception in org.h2.tools.Server.createTcpServer()", t);
            throw new IllegalStateException("Unchecked exception in org.h2.tools.Server.createTcpServer()", t);
        }
    }


    public void initH2Console(ServletContext servletContext) {
        try {
            ClassLoader loader = Thread.currentThread().getContextClassLoader();
            Class<?> servletClass = Class.forName("org.h2.server.web.JakartaWebServlet", true, loader);
            Servlet servlet = (Servlet) servletClass.getDeclaredConstructor().newInstance();
            ServletRegistration.Dynamic registration = servletContext.addServlet("h2-console", servlet);
            registration.addMapping("/h2-console/*");
            registration.setInitParameter("webAllowOthers", "true");
            registration.setInitParameter("webPort", "8092");
            registration.setInitParameter("webSSL", "false");
            registration.setLoadOnStartup(1);
        } catch (ClassNotFoundException | LinkageError | NoSuchMethodException
                 | IllegalAccessException | InstantiationException |
                 InvocationTargetException e) {
            log.error("Failed to initialize H2 console", e);
            throw new IllegalStateException("Failed to initialize H2 console", e);
        }
    }
}
