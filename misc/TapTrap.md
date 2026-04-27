This is my overal understanding and attempt to Proof of Concept the TapTrap vulnerability released here: https://taptrap.click/#home

Please read through their information first, and read their paper here: https://taptrap.click/usenix25_taptrap_paper.pdf

## Summary

So TapTrap is a vulnerability that is similar to Tapjacking Attacks where the goal is to fool the user into tapping on the phone to give permissions for the application. This is a novel technique where the focus is to abuse animations into being opaque, like you would with Clickjacking, to fool the user into granting permissions. 

### Methodology to identify vulnerable code

So the research team identified 4 ways they identify vulnerable applications statically:
1. The application has an exported activity, searching in Android Manifest for exported="true", as well as identifying if enabled attributes to confirm the activity has any declared permissions required to open it.
2. Is Same-Task Launchable, is the application launchable into the same task as any other app. Searching for the launchmode of the above activity as either "standard" or "singleTop"
3. Then looking if the application has any animation custom overrides, creating a callgraph with androguard: "androguard cg \<apkfile\> -o \<output file\>", then searching for "calls to Activity.overridePendingTransition" and trace the call graph back to an enter method of the activity. If "overridePendingTransition" is called this mitigates the vulnerability. If the call is made after a call to startActivity that is also tossed as not applicable.
4. Does the application not wait for the animation to complete before handling user input. Check if the activity overrides the "onEnterAnimationComplete" callback. 

