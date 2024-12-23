use common::constants::IntoEnumIterator;
use common::constants::CONST_ENUM;
use common::error::MulTeeErrCode;
use std::fs;

fn main() {
  let mut java_enum = String::new();
  let mut java_const = String::new();

  for (nam, val) in CONST_ENUM {
    java_const.push_str(format!("  public static final long {} = {};\n", nam, val).as_str());
  }

  for et in MulTeeErrCode::iter() {
    java_enum.push_str(format!("    {:?}({}),\n", et, et as u32).as_str());
  }

  let java_const = format!(
    "\
package cc.multee;

// Generated file

public class Const {{
{}}}
",
    java_const
  );

  java_enum.truncate(java_enum.len() - 2);
  java_enum.push(';');
  let java_enum = format!(
    "\
package cc.multee;

// Generated file

public enum Errors {{
{}

  final int code;

  Errors( final int v ) {{
    this.code = v;
  }}
}}
",
    java_enum
  );

  fs::write(
    "../multee-java/src/main/java/cc/multee/Const.java",
    java_const.as_str(),
  )
  .expect("Unable to write file");
  fs::write(
    "../multee-java/src/main/java/cc/multee/Errors.java",
    java_enum.as_str(),
  )
  .expect("Unable to write file");
}
