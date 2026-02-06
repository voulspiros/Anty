use crate::agents;

/// List all available security rules
pub fn list_rules() {
    println!();
    println!("🐜 Anty — Available Security Agents & Rules");
    println!("{}", "━".repeat(55));
    println!();

    let all_agents = agents::all_agents();

    for agent in &all_agents {
        println!("  📋 {} ", agent.name());
        println!("     {}", agent.description());
        println!();
    }

    println!("{}", "━".repeat(55));
    println!(
        "  {} agents loaded",
        all_agents.len()
    );
    println!();
    println!("  Run `anty scan .` to scan your project");
    println!("  Run `anty scan . --agents secrets` to run specific agents");
    println!();
}
