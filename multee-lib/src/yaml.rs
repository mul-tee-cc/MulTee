use yaml_rust2::yaml::{Hash, Yaml};
use yaml_rust2::YamlEmitter;

pub(crate) trait Put {
  fn put_int(self: Self, key: &str, val: i64) -> Self;
  fn put_str<T: ToString>(self: Self, key: &str, val: T) -> Self;
  fn put_hash(self: Self, key: &str, val: Hash) -> Self;
  fn get(self: Self) -> Self;
  fn dump(self: Self) -> String;
}

impl Put for Hash {
  fn put_int(mut self: Self, key: &str, val: i64) -> Self {
    let _ignore = self.insert(Yaml::String(key.to_string()), Yaml::Integer(val));
    self
  }
  fn put_str<T: ToString>(mut self: Self, key: &str, val: T) -> Self {
    let _ignore = self.insert(Yaml::String(key.to_string()), Yaml::String(val.to_string()));
    self
  }
  fn put_hash(mut self: Self, key: &str, val: Hash) -> Self {
    let _ignore = self.insert(Yaml::String(key.to_string()), Yaml::Hash(val));
    self
  }
  fn get(self: Self) -> Self {
    self
  }
  fn dump(self: Self) -> String {
    let mut out_str = String::new();
    let mut emitter = YamlEmitter::new(&mut out_str);
    emitter.dump(&Yaml::Hash(self)).unwrap();
    out_str
  }
}
