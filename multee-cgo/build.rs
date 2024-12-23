use common::constants::IntoEnumIterator;
use common::constants::CONST_ENUM;
use common::error::MulTeeErrCode;
use std::fs;

fn main() {
  let mut go_enum = String::new();
  let mut go_enum2 = String::new();
  let mut go_const = String::new();

  for (nam, val) in CONST_ENUM {
    go_const.push_str(format!("  CONST_{} = {}\n", nam, val).as_str());
  }

  for et in MulTeeErrCode::iter() {
    go_enum.push_str(format!("  ERR_{:?} = {}\n", et, et as u32).as_str());
    go_enum2.push_str(format!("    case ERR_{:?}: return \"{:?}\"\n", et, et).as_str());
  }

  let go_const = format!(
    "\
package multee

// Generated file

const (
{})
",
    go_const
  );

  let go_enum = format!(
    "\
package multee

// Generated file

type ErrCode int32

const (
{})

func (s ErrCode) String() string {{
  switch s {{
    {}
  }}
  return \"UNKNOWN\"
}}
",
    go_enum, go_enum2
  );

  fs::write("../multee-golang/const.go", go_const.as_str()).expect("Unable to write file");
  fs::write("../multee-golang/err.go", go_enum.as_str()).expect("Unable to write file");
}
