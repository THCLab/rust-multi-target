use crate::prefix::Prefix;
use crate::state::IdentifierState;
use serde::{Deserialize, Serialize};
pub mod event_data;
pub mod sections;

use self::event_data::EventData;
use crate::error::Error;
use crate::state::EventSemantics;

#[derive(Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "id")]
    pub prefix: Prefix,

    // TODO a backhash/digest of previous message?
    pub sn: u64,

    #[serde(flatten)]
    pub event_data: EventData,
}

impl EventSemantics for Event {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self.event_data {
            EventData::Icp(_) => {
                // ICP events require the state to be uninitialized
                if state != IdentifierState::default() || self.sn != 0 {
                    return Err(Error::SemanticError("SN is not correct".to_string()));
                }
            }
            _ => {
                // prefix must equal. sn must be incremented
                if self.prefix != state.prefix {
                    return Err(Error::SemanticError("Prefix does not match".to_string()));
                } else if self.sn != state.sn + 1 {
                    return Err(Error::SemanticError("SN is not correct".to_string()));
                }
            }
        };

        Ok(IdentifierState {
            sn: self.sn,
            prefix: self.prefix.clone(),
            ..self.event_data.apply_to(state)?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn ser_der() -> Result<(), serde_json::Error> {
        let event_str = "{
  \"id\": \"AXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148\",
  \"sn\": 0,
  \"ilk\": \"icp\",
  \"sith\": 2,
  \"keys\":
  [
    \"AWoNZsa88VrTkep6HQt27fTh-4HA8tr54sHON1vWl6FE\",
    \"A8tr54sHON1vWVrTkep6H-4HAl6FEQt27fThWoNZsa88\",
    \"AVrTkep6HHA8tr54sHON1Qt27fThWoNZsa88-4vWl6FE\"
  ],
  \"next\": \"EWoNZsa88VrTkep6HQt27fTh-4HA8tr54sHON1vWl6FE\",
  \"toad\": 2,
  \"wits\":
  [
    \"AVrTkep6H-Qt27fThWoNZsa884HA8tr54sHON1vWl6FE\",
    \"AHON1vWl6FEQt27fThWoNZsa88VrTkep6H-4HA8tr54s\",
    \"AThWoNZsa88VrTkeQt27fp6H-4HA8tr54sHON1vWl6FE\"
  ]
}";

        let event: Event = serde_json::from_str(event_str)?;

        print!("\n{}\n", serde_json::to_string(&event)?);

        Ok(())
    }
}
