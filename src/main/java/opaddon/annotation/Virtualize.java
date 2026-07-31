package opaddon.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marker annotation. Methods annotated with {@code @Virtualize} will have their
 * bytecode replaced with a call into the embedded VM interpreter.
 *
 * Only annotate methods that are NOT performance-critical (license checks, config
 * parsing, init logic). The VM interpreter is 10-100x slower than native execution.
 */
@Retention(RetentionPolicy.CLASS)
@Target(ElementType.METHOD)
public @interface Virtualize {
}
