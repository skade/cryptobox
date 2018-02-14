// Copyright (C) 2018 Wire Swiss GmbH <support@wire.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

extern crate proteus;
extern crate cbor;

pub mod identity;

use identity::Identity;
use proteus::keys::{IdentityKeyPair, PreKey, PreKeyId};
use proteus::session::Session;
use std::sync::Arc;

pub type Result<T> = std::result::Result<T, Box<::std::error::Error>>;

pub trait Store {
    fn load_session(&self, li: Arc<IdentityKeyPair>, id: &str) -> Result<Option<Session<Arc<IdentityKeyPair>>>>;
    fn save_session(&self, id: &str, s: &Session<Arc<IdentityKeyPair>>) -> Result<()>;
    fn delete_session(&self, id: &str) -> Result<()>;

    fn load_identity(&self) -> Result<Option<Identity>>;
    fn save_identity(&self, id: &Identity) -> Result<()>;

    fn load_prekey(&self, id: PreKeyId) -> Result<Option<PreKey>>;
    fn add_prekey(&self, key: &PreKey) -> Result<()>;
    fn delete_prekey(&self, id: PreKeyId) -> Result<()>;
}
