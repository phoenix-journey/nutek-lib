pub mod hello {
    /// This is my cat's drawing of the key
    ///
    /// # Examples
    ///
    /// ```
    /// // Draw a key
    /// // If you pass --test to `rustdoc`, it will even test it for you!
    /// let person = nutek_lib::hello::hi_nutek();
    /// println!("{}", person);
    /// ```
    pub fn hi_nutek() -> &'static str {
r#"::::    ::: :::    ::: ::::::::::: :::::::::: :::    ::: 
:+:+:   :+: :+:    :+:     :+:     :+:        :+:   :+:  
:+:+:+  +:+ +:+    +:+     +:+     +:+        +:+  +:+   
+#+ +:+ +#+ +#+    +:+     +#+     +#++:++#   +#++:++    
+#+  +#+#+# +#+    +#+     +#+     +#+        +#+  +#+   
#+#   #+#+# #+#    #+#     #+#     #+#        #+#   #+#  
###    ####  ########      ###     ########## ###    ### "#
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    use crate::hello::hi_nutek;
    #[test]
    fn hello_msg() {
        eprintln!("{}", hi_nutek())
    }
}
