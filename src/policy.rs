//! A narrow request gate for the documented ChatGPT-plan Responses route.
//! It is one layer of a broker; transport, signed lane grants and response
//! quarantine must also run outside the agent's process and mount namespace.

use serde_json::Value;

const UNSUPPORTED: &[&str] = &[
    "background",
    "conversation",
    "max_output_tokens",
    "max_tool_calls",
    "metadata",
    "moderation",
    "multi_agent",
    "prompt",
    "prompt_cache_retention",
    "safety_identifier",
    "temperature",
    "top_logprobs",
    "top_p",
    "truncation",
    "user",
    "previous_response_id",
    "service_tier",
];

const HOSTED_TOOLS: &[&str] = &[
    "image_generation",
    "file_search",
    "code_interpreter",
    "computer_use",
    "mcp",
    "tool_search",
];

pub fn valid_plan_request(value: &Value, allowed_model: &str) -> bool {
    let Some(request) = value.as_object() else {
        return false;
    };
    request.get("model").and_then(Value::as_str) == Some(allowed_model)
        && request.get("store") == Some(&Value::Bool(false))
        && request.get("stream") == Some(&Value::Bool(true))
        && request
            .get("input")
            .and_then(Value::as_array)
            .is_some_and(|input| {
                !input.is_empty()
                    && input.iter().all(|item| {
                        item.as_object().is_none_or(|part| {
                            part.get("role").and_then(Value::as_str) != Some("system")
                        })
                    })
            })
        && UNSUPPORTED
            .iter()
            .all(|field| !request.contains_key(*field))
        && request
            .get("tools")
            .and_then(Value::as_array)
            .is_none_or(|tools| {
                tools.iter().all(|tool| {
                    !tool
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| HOSTED_TOOLS.contains(&kind))
                })
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gate_requires_plan_transport_and_exact_model() {
        let good = json!({"model":"example-model","input":[{"role":"user","content":"hi"}],"store":false,"stream":true});
        assert!(valid_plan_request(&good, "example-model"));
        assert!(!valid_plan_request(&good, "another-model"));
        for (field, value) in [
            ("store", json!(true)),
            ("stream", json!(false)),
            ("input", json!("hi")),
            ("service_tier", json!("priority")),
            ("previous_response_id", json!("abc")),
        ] {
            let mut bad = good.clone();
            bad[field] = value;
            assert!(
                !valid_plan_request(&bad, "example-model"),
                "accepted {field}"
            );
        }
        let mut bad = good.clone();
        bad["input"][0]["role"] = json!("system");
        assert!(!valid_plan_request(&bad, "example-model"));
        let mut bad = good.clone();
        bad["tools"] = json!([{"type":"tool_search"}]);
        assert!(!valid_plan_request(&bad, "example-model"));
    }
}
